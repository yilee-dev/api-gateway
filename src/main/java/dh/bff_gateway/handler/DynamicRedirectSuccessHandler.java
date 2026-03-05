package dh.bff_gateway.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import reactor.core.publisher.Mono;

import java.net.URI;

public class DynamicRedirectSuccessHandler extends RedirectServerAuthenticationSuccessHandler {

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        return webFilterExchange.getExchange().getSession()
                .flatMap(session -> {
                    String clientUrl = session.getAttribute("CLIENT_ORIGIN_URL");

                    if (clientUrl != null) {
                        this.setLocation(URI.create(clientUrl));
                    } else {
                        this.setLocation(URI.create("/"));
                    }

                    return super.onAuthenticationSuccess(webFilterExchange, authentication);
                });
    }
}
