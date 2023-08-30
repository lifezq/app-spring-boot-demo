package demo.web;


import demo.support.TokenAccessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import java.util.stream.Collectors;

@Controller
class UiController {

    @Autowired
    private TokenAccessor tokenAccessor;

    @GetMapping("/")
    public String showIndex(Model model, Authentication auth, HttpServletRequest request) {
        OAuth2AccessToken accessToken = tokenAccessor.getAccessToken(auth);
        var roleNames = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        model.addAttribute("roleNames", roleNames);
        return "index";
    }
}
