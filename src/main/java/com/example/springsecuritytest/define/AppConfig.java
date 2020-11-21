package com.example.springsecuritytest.define;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * application.ymlの値を取得するためのコンポーネント
 */
@Data
@Component
@ConfigurationProperties(prefix = "app")
public class AppConfig {

    // フロントエンドのURL
    private String frontendUrl;
}
