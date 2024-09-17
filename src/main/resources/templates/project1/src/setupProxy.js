// src/setupProxy.js
const { createProxyMiddleware } = require("http-proxy-middleware");

module.exports = function (app) {
    app.use(
        "/api", // 모든 /api 경로를 프록시합니다.
        createProxyMiddleware({
            target: "http://localhost:8080",
            changeOrigin: true,
            pathRewrite: { "^/api": "" }, // 프록시 경로에서 "/api"를 제거합니다.
        })
    );
};
