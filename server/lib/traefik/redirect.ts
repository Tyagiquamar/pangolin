import logger from "@server/logger";
import config from "@server/lib/config";
import {
    buildHostRule,
    appendPathMatch,
    computeRoutePriority
} from "@server/lib/traefik/rule";

export type RedirectRouteRow = {
    redirectId: number;
    /** Host the redirect listens on (resource fullDomain or subdomain.baseDomain). */
    fullDomain: string;
    hasSubdomain: boolean;
    wildcard: boolean | null;
    ssl: boolean;
    matchPath: string;
    pathMatchType: string;
    priority: number | null;
    domainCertResolver?: string | null;
    preferWildcardCert?: boolean | null;
};

/**
 * Add Traefik routers for redirects. Like resources, every request is sent
 * through badger, which looks up the redirect by host/path, applies any
 * path rewrite and answers with the redirect itself - Traefik only has to
 * match the host (+ path) and terminate TLS. Redirects have no backend, so
 * the routers point at Traefik's built-in noop@internal service.
 * TLS/cert-resolver handling differs between the OSS and private
 * (pangolin-dns aware) config generators, so callers resolve that via
 * resolveTls - returning null skips the redirect (no valid cert yet).
 */
export function buildRedirectConfig(params: {
    config_output: any;
    redirects: RedirectRouteRow[];
    badgerMiddlewareName: string;
    redirectHttpsMiddlewareName: string;
    resolveTls: (row: RedirectRouteRow) => any | null;
}): void {
    const {
        config_output,
        redirects,
        badgerMiddlewareName,
        redirectHttpsMiddlewareName,
        resolveTls
    } = params;

    if (redirects.length === 0) {
        return;
    }

    const httpEntrypoint = config.getRawConfig().traefik.http_entrypoint;
    const httpsEntrypoint = config.getRawConfig().traefik.https_entrypoint;
    const additionalMiddlewares =
        config.getRawConfig().traefik.additional_middlewares || [];
    const routerMiddlewares = [badgerMiddlewareName, ...additionalMiddlewares];

    for (const redirect of redirects) {
        const routerName = `redirect-${redirect.redirectId}-router`;

        let tls: any = {};
        if (redirect.ssl) {
            tls = resolveTls(redirect);
            if (tls === null) {
                continue;
            }
        }

        if (!config_output.http.routers) {
            config_output.http.routers = {};
        }

        if (redirect.pathMatchType === "regex") {
            try {
                new RegExp(redirect.matchPath);
            } catch {
                logger.debug(
                    `Invalid regex pattern in redirect ${redirect.redirectId} match path: ${redirect.matchPath}`
                );
                continue;
            }
        }

        const rule = appendPathMatch(
            buildHostRule(redirect.fullDomain, redirect.wildcard),
            redirect.matchPath,
            redirect.pathMatchType
        );

        // A redirect attached to a resource must win over that resource's
        // router at the same host/path specificity, so nudge derived
        // priorities up by one. Explicit priorities are used as-is.
        const hasExplicitPriority =
            !!redirect.priority && redirect.priority !== 100;
        const priority =
            computeRoutePriority(
                redirect.priority,
                redirect.matchPath,
                redirect.pathMatchType
            ) + (hasExplicitPriority ? 0 : 1);

        if (redirect.ssl) {
            config_output.http.routers[`${routerName}-redirect`] = {
                entryPoints: [httpEntrypoint],
                middlewares: [redirectHttpsMiddlewareName],
                service: "noop@internal",
                rule,
                priority
            };
        }

        config_output.http.routers[routerName] = {
            entryPoints: [redirect.ssl ? httpsEntrypoint : httpEntrypoint],
            middlewares: routerMiddlewares,
            service: "noop@internal",
            rule,
            priority,
            ...(redirect.ssl ? { tls } : {})
        };
    }
}
