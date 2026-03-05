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
                        // 세션에서 꺼낸 클라이언트의 IP:Port 주소로 리다이렉트 경로 설정
                        this.setLocation(URI.create(clientUrl));
                    } else {
                        this.setLocation(URI.create("/"));
                    }

                    // 부모 클래스의 기본 동작(리다이렉트 수행) 호출
                    return super.onAuthenticationSuccess(webFilterExchange, authentication);
                });
    }
}
