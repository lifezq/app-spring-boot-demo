package demo.web;


import com.alibaba.fastjson.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("user")
public class UserInfoController {

    @Resource
    private RestTemplate restTemplate;

    @RequestMapping(value = "/me", method = RequestMethod.GET)
    public Object getToken(HttpServletRequest request){
        String authorization = request.getHeader("Authorization");
        HttpHeaders headers1 = new HttpHeaders();
        headers1.add("Authorization", "Bearer " + authorization);

        HttpEntity<Object> objectHttpEntity = new HttpEntity<>(headers1);
        ResponseEntity<Object> exchange = restTemplate.exchange("http://localhost:8080/auth/v1/users/me", HttpMethod.GET, objectHttpEntity, Object.class);
        Object body = exchange.getBody();
        JSONObject jsonObject = JSONObject.parseObject(JSONObject.toJSONString(body));
        JSONObject user = jsonObject.getJSONObject("user");
        return user;
    }

}
