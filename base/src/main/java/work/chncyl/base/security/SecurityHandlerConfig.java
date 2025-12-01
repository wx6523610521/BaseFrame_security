package work.chncyl.base.security;

import com.alibaba.fastjson2.JSON;
import org.springframework.beans.BeanUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import work.chncyl.base.global.tools.result.ApiResult;
import work.chncyl.base.security.entity.LoginSuccessVo;
import work.chncyl.base.security.entity.LoginUserDetail;
import work.chncyl.base.security.utils.JwtUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 安全处理器配置类
 */
@Configuration
public class SecurityHandlerConfig {
    /**
     * 登录成功处理器
     */
    public static AuthenticationSuccessHandler loginSuccessHandler() {
        return new AuthenticationSuccessHandler() {

            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                LoginUserDetail userDetail = (LoginUserDetail) authentication.getPrincipal();
                // 使用JwtUtil的generateToken方法，根据配置决定使用哪种算法
                String token = JwtUtil.genToken(userDetail);
                response.setStatus(200);
                response.setContentType("application/json");
                PrintWriter writer = response.getWriter();
                LoginSuccessVo vo=new LoginSuccessVo();
                BeanUtils.copyProperties(userDetail, vo);
                vo.setUserName(userDetail.getUsername());
                vo.setAccessToken(token);
                ApiResult<LoginSuccessVo> ok = ApiResult.OK(vo);
                writer.write(JSON.toJSONString(ok));
                writer.flush();
                writer.close();
            }
        };
    }

    /**
     * 登录失败处理器
     */
    public static AuthenticationFailureHandler loginFailureHandler() {
        return new AuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                response.setStatus(401);
                response.setContentType("application/json;charset=UTF-8");
                PrintWriter writer = response.getWriter();
                ApiResult<Object> result = ApiResult.error(401, exception.getMessage());
                exception.printStackTrace();
                writer.write(JSON.toJSONString(result));
                writer.flush();
                writer.close();
            }
        };
    }

    /**
     * 登出处理器
     */
    public static LogoutHandler logoutHandler() {
        return (request, response, authentication) -> JwtUtil.lapsedToken();
    }

    /**
     * 登出成功处理器
     */
    public static LogoutSuccessHandler logoutSuccessHandler() {
        // 登出成功处理器
        return (request, response, authentication) -> {

        };
    }
}
