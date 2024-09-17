import { useState } from "react";
import { useNavigate } from "react-router-dom";
import styles from "./Login.module.scss";
import {login} from "../api.ts";

function Login() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const data = await login(username, password); // 로그인 요청
            const { accessToken } = data;

            // accessToken을 쿠키 또는 세션 스토리지에 저장
            localStorage.setItem("accessToken", accessToken);
            navigate("/"); // 로그인 성공 후 메인 페이지로 이동
        } catch (error) {
            console.error("로그인 실패:", error);
            alert("로그인에 실패했습니다.");
        }
    };

    const goToSignup = () => {
        // 회원가입 페이지로 이동
        navigate("/join");
    };

    return (
        <div className={styles.login}>
            <div className={styles.login__container}>
                <h1 className={styles.login__container__title}>로그인</h1>
                <form className={styles.login__container__form} onSubmit={handleSubmit}>
                    <input
                        type="text"
                        placeholder="아이디"
                        className={styles.login__container__form__input}
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                    />
                    <input
                        type="password"
                        placeholder="비밀번호"
                        className={styles.login__container__form__input}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                    <button
                        type="submit"
                        className={styles.login__container__form__button}
                        onClick={handleSubmit}
                    >
                        로그인
                    </button>
                    <span className={styles.login__container__form__forgot}>
            비밀번호를 잊으셨나요?
          </span>
                    <span className={styles.login__container__form__signup} onClick={goToSignup}>
            회원가입
          </span>
                </form>
            </div>
        </div>
    );
}

export default Login;
