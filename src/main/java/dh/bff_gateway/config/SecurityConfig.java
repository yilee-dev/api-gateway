package dh.bff_gateway.config;

import dh.bff_gateway.filter.CsrfTokenResponseHeaderFilter;
import dh.bff_gateway.handler.DynamicLogoutSuccessHandler;
import dh.bff_gateway.handler.DynamicRedirectSuccessHandler;
import dh.bff_gateway.handler.PostLogoutSuccessHandler;
import dh.bff_gateway.repository.OriginPreservingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;


@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final OriginPreservingRepository repository;
    private final ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {

        CookieServerCsrfTokenRepository cookieServerCsrfTokenRepository = new CookieServerCsrfTokenRepository();
        cookieServerCsrfTokenRepository.setCookieCustomizer(cookie ->
                cookie.httpOnly(true)
                        .secure(false)
                        .sameSite("Lax"));

        OidcClientInitiatedServerLogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);

        return http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(cookieServerCsrfTokenRepository)
                                .requireCsrfProtectionMatcher(exchange -> {
                                    return ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/logout")
                                            .matches(exchange)
                                            .flatMap(matchResult -> matchResult.isMatch() ?
                                                    ServerWebExchangeMatcher.MatchResult.notMatch() :
                                                    CsrfWebFilter.DEFAULT_CSRF_MATCHER.matches(exchange));
                                })
                        )
                .addFilterAfter(new CsrfTokenResponseHeaderFilter(), SecurityWebFiltersOrder.CSRF)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/login/**", "/public/**", "/logout", "/logout/**").permitAll()
                        .anyExchange().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .authorizationRequestRepository(repository)
                        .authenticationSuccessHandler(new DynamicRedirectSuccessHandler()))
                .requestCache(requestCacheSpec -> requestCacheSpec
                        .requestCache(new WebSessionServerRequestCache()))
                .logout(logout -> logout
                        .requiresLogout(ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST,"/logout"))
                        .logoutSuccessHandler(logoutSuccessHandler))
                .build();
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsWebFilter() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.addAllowedOrigin("http://10.117.9.40:3000");
        corsConfiguration.addAllowedOrigin("http://10.117.9.40:4000");
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"));

        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
        return urlBasedCorsConfigurationSource;
    }
}

