package dh.bff_gateway.handler;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

public class PostLogoutSuccessHandler implements ServerLogoutSuccessHandler {
    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        ServerWebExchange webExchange = exchange.getExchange();

        return webExchange.getSession()
                .flatMap(WebSession::invalidate) // 1. 세션 확실히 삭제
                .then(Mono.fromRunnable(() -> {
                    webExchange.getResponse().setStatusCode(HttpStatus.OK);
                    webExchange.getResponse().getHeaders().add("Content-Type", "application/json");
                }));
    }
}
