package dh.bff_gateway.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

public class DynamicLogoutSuccessHandler extends RedirectServerLogoutSuccessHandler {
    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        ServerWebExchange webExchange = exchange.getExchange();

        String origin = webExchange.getRequest().getHeaders().getFirst("Referer");
        if (origin == null || origin.isEmpty()) {
            URI uri = webExchange.getRequest().getURI();
            origin = uri.getScheme() + "://" + uri.getAuthority();
        }

        this.setLogoutSuccessUrl(URI.create(origin));

        return super.onLogoutSuccess(exchange, authentication);
    }
}
