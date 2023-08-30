package demo.support.zitadel;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


@Component
public class MyAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {

        if (authentication != null) {
            DefaultOidcUser oidcUser = (DefaultOidcUser) authentication.getPrincipal();
            Cookie cookie = new Cookie("login_hint", oidcUser.getPreferredUsername());
            cookie.setPath("/");
            cookie.setDomain("localhost");
            cookie.setMaxAge(60 * 60 * 24);
            cookie.setHttpOnly(false);
            response.addCookie(cookie);
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }
}
