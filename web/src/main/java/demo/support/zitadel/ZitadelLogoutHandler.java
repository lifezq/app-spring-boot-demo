package demo.support.zitadel;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class ZitadelLogoutHandler implements LogoutHandler {

    @Value("${zitadel.endsession-endpoint}")
    public String ZITADEL_END_SESSION_ENDPOINT;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication auth) {
        var defaultRedirectUri = generateAppUri(request);
        try {
            var principal = (DefaultOidcUser) auth.getPrincipal();
            var idToken = principal.getIdToken();

            log.debug("Propagate logout to zitadel for user. userId={}", idToken.getSubject());

            var idTokenValue = idToken.getTokenValue();

            var logoutUrl = createZitadelLogoutUrl(idTokenValue, defaultRedirectUri);

            try {
                response.sendRedirect(logoutUrl);
            } catch (IOException e) {
                log.error("Could not propagate logout for user to zitadel. userId={}", idToken.getSubject(), e);
            }
        } catch (NullPointerException e) {
            try {
                response.sendRedirect(defaultRedirectUri);
            } catch (IOException ioException) {
                ioException.printStackTrace();
            } finally {
                log.error("Could not propagate logout for user to zitadel", e);
            }
        }
    }

    private String generateAppUri(HttpServletRequest request) {
        var hostname = request.getServerName() + ":" + request.getServerPort();
        var isStandardHttps = "https".equals(request.getScheme()) && request.getServerPort() == 443;
        var isStandardHttp = "http".equals(request.getScheme()) && request.getServerPort() == 80;
        if (isStandardHttps || isStandardHttp) {
            hostname = request.getServerName();
        }
        return request.getScheme() + "://" + hostname + request.getContextPath();
    }

    private String createZitadelLogoutUrl(String idTokenValue, String postRedirectUri) {
        return ZITADEL_END_SESSION_ENDPOINT + //
                "?id_token_hint=" + idTokenValue //
                + "&post_logout_redirect_uri=" + postRedirectUri;
    }
}
