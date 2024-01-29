package io.github.toquery.example.spring.security.multiple.authentication.admin;

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
public class AdminControllerTests {


    @Resource
    private MockMvc mockMvc;

    @Test
    void adminAuthentication() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/admin")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("admin", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("admin"));
    }

    @Test
    void adminAuthenticationError401() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/admin")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("error", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void adminAuthenticationError403() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/admin")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("root", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

}
