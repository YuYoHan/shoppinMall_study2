import { useState } from "react";
import styles from "./Join.module.scss";
import {join} from "../api.ts";

function Signup() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (password !== confirmPassword) {
            alert("비밀번호가 일치하지 않습니다.");
            return;
        }
        try {
            const data = await join(username, password); // 회원가입 요청
            console.log("회원가입 성공:", data);
        } catch (error) {
            console.error("회원가입 실패:", error);
            alert("회원가입에 실패했습니다.");
        }
    };

    return (
        <div className={styles.signup}>
            <div className={styles.signup__container}>
                <h1 className={styles.signup__container__title}>회원가입</h1>
                <form className={styles.signup__container__form} onSubmit={handleSubmit}>
                    <input
                        type="text"
                        placeholder="아이디"
                        className={styles.signup__container__form__input}
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                    />
                    <input
                        type="password"
                        placeholder="비밀번호"
                        className={styles.signup__container__form__input}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                    />
                    <input
                        type="password"
                        placeholder="비밀번호 확인"
                        className={styles.signup__container__form__input}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                    />
                    <button
                        type="submit"
                        className={styles.signup__container__form__button}
                        onClick={handleSubmit}
                    >
                        회원가입
                    </button>
                </form>
            </div>
        </div>
    );
}

export default Signup;
