package com.hmall.gateway.filters;

import cn.hutool.core.text.AntPathMatcher;
import com.hmall.common.exception.UnauthorizedException;
import com.hmall.gateway.config.AuthProperties;
import com.hmall.gateway.utils.JwtTool;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;


@Component
@RequiredArgsConstructor
public class AuthGlobalFilter implements GlobalFilter, Ordered {

    private final AuthProperties authProperties;
    private final JwtTool jwtTool;
    private final AntPathMatcher antPathMatcher = new AntPathMatcher();
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 获取请求路径判断请求是否放行，获取token，校验并解析token
        ServerHttpRequest request = exchange.getRequest();

        if (ifExclude(request.getPath().toString())) {
            return chain.filter(exchange);
        }

        String token=null;
        List<String> authorization = request.getHeaders().get("authorization");
        if (authorization!=null&& !authorization.isEmpty()){
            token = authorization.get(0);
        }
        Long userId=null;
        try {
             userId = jwtTool.parseToken(token);
        } catch (UnauthorizedException e){
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return response.setComplete();
        }
        // TODO 传递用户信息
        String userInfo = userId.toString();
        System.out.println("userId = " + userId);
        ServerWebExchange webExchange = exchange.mutate()
                .request(builder -> builder.header("user-info", userInfo))
                .build();

        return chain.filter(webExchange);

    }

    private boolean ifExclude(String path) {
        List<String> excludePaths = authProperties.getExcludePaths();
        for (String excludePath : excludePaths) {
            if (antPathMatcher.match(excludePath, path)){
                return true;
            }
        }
        return false;
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
