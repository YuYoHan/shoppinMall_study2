import axios from "axios";

// 로그인 API
export const login = async (username, password) => {
    const response = await axios.post("/api/login", {
        username,
        password,
    });
    return response.data; // accessToken을 반환
};

// 회원가입 API
export const join = async (username, password) => {
    const response = await axios.post("/api/join", {
        username,
        password,
    });
    return response.data; // 필요한 데이터 반환
};
