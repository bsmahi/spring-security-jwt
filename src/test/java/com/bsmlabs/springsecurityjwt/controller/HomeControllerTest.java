package com.bsmlabs.springsecurityjwt.controller;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bsmlabs.springsecurityjwt.config.SecurityConfig;
import com.bsmlabs.springsecurityjwt.services.JwtTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@WebMvcTest({HomeController.class, AuthenticationController.class})
@Import({SecurityConfig.class, JwtTokenService.class})
public class HomeControllerTest {
    @Autowired
    MockMvc mvc;

    @Test
    void shouldReturnUnauthenticatedThen401() throws Exception {
        this.mvc.perform(get("/"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldReturnWhenAuthenticatedThenSaysHelloUser() throws Exception {
        MvcResult result = this.mvc.perform(post("/generate-token")
                        .with(httpBasic("in28minutes", "password")))
                .andExpect(status().isOk())
                .andReturn();

        String token = result.getResponse().getContentAsString();

        this.mvc.perform(get("/")
                        .header("Authorization", "Bearer " + token))
                .andExpect(content().string("Hello, in28minutes"));
    }

    @Test
    @WithMockUser
    public void shouldReturnWithMockUserStatusIsOK() throws Exception {
        this.mvc.perform(get("/"))
                .andExpect(status().isOk());
    }
}
