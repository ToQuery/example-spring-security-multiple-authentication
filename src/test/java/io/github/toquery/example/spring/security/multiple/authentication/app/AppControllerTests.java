package io.github.toquery.example.spring.security.multiple.authentication.app;

import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
@SpringBootTest
@AutoConfigureMockMvc
public class AppControllerTests {

    @Resource
    private MockMvc mockMvc;
    @Test
    void appAuthentication() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/app")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("app", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("app"));
    }

    @Test
    void appAuthenticationError401() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/app")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("error", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void appAuthenticationError403() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/app")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("root", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

}
