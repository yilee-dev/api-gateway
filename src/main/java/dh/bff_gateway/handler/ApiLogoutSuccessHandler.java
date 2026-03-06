package dh.bff_gateway.handler;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

@Component
public class ApiLogoutSuccessHandler implements ServerLogoutSuccessHandler {
    @Override
    public Mono<Void> onLogoutSuccess(WebFilterExchange exchange, Authentication authentication) {
        ServerWebExchange webExchange = exchange.getExchange();

        return webExchange.getSession()
                .flatMap(WebSession::invalidate)
                .then(Mono.defer(() -> {
                    String origin = webExchange.getResponse().getHeaders().getFirst("Referer");

                    String logoutUrl = "http://10.100.104.24:8080/realms/donghee/protocol/openid-connect/logout"
                            + "?client_id=api-gateway"
                            + "&post_logout_redirect_uri=" + origin + "/";

                    ServerHttpResponse response = webExchange.getResponse();
                    response.setStatusCode(HttpStatus.OK);
                    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

                    String json = "{\"logoutUrl\": \"" + logoutUrl + "\"}";
                    DataBuffer buffer = response.bufferFactory().wrap(json.getBytes());
                    return response.writeWith(Mono.just(buffer));
                }));
    }
}
