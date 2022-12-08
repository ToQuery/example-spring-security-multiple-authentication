package io.github.toquery.example.spring.security.multiple.authentication;

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
class ExampleSpringSecurityMultipleAuthenticationApplicationTests {


    @Resource
    private MockMvc mockMvc;


    @Test
    void contextLoads() {
    }

    @Test
    void index() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders.get("/")
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("root"));
    }

    @Test
    void rootAuthentication() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/index")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("root", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("root"));
    }

    @Test
    void rootAuthenticationError401() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/index")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("error", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void rootAuthenticationError403() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/index")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("open", "123456"))
                )
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is4xxClientError());
    }

    @Test
    void openAuthentication() throws Exception {
        mockMvc.perform(
                        MockMvcRequestBuilders
                                .get("/open")
                                .with(SecurityMockMvcRequestPostProcessors.httpBasic("open", "123456"))
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
