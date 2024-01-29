package io.github.toquery.example.spring.security.multiple.authentication.open;

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
public class OpenControllerTests {

    @Resource
    private MockMvc mockMvc;
    @Test
    void openAuthentication() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/open")
                                .with(SecurityMockMvcRequestPostProcessors.jwt())
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("open"));
    }

    @Test
    void openAuthenticationError401() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/open")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("error", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void openAuthenticationError403() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/open")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("root", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }


}
