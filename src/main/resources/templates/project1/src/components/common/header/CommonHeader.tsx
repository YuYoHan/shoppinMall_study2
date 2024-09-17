import styles from "./CommonHeader.module.scss";
import { useNavigate } from "react-router-dom";
import logoIcon from "../../../assets/images/image-logo.png";
import Modal from "../../../pages/modal/Modal";  // 모달 컴포넌트 가져오기
import Login from "../header/navigation/login/Login";  // 로그인 컴포넌트 가져오기
import Signup from "../header/navigation/join/Join";  // 회원가입 컴포넌트 가져오기
import { useState } from "react";

function CommonHeader() {
  const navigate = useNavigate();
  // 북마크 페이지로 이동
  const moveToPage = (filter: string) => {
    if (filter === "main") {
      navigate("/");
    } else if (filter === 'bookmark'){
      navigate("/bookmark");
    } else if (filter === "login"){
      navigate("/login")
    } else {
      navigate("/join")
    }
  };
  // isLoginOpen: 로그인 모달이 열려 있는지 여부를 관리하는 상태입니다.
  // false이면 모달이 닫혀 있고, true이면 모달이 열립니다.
  const [isLoginOpen, setLoginOpen] = useState(false);
  const [isSignupOpen, setSignupOpen] = useState(false);
  const openLoginModal = () => setLoginOpen(true);
  const openSignupModal = () => setSignupOpen(true);
  const closeModal = () => {
    setLoginOpen(false);
    setSignupOpen(false);
  };
  return (
    <header className={styles.header}>
      <div
        className={styles.header__logoBox}
        onClick={() => moveToPage("main")}
      >
        <img src={logoIcon} alt="" className={styles.header__logoBox__logo} />
        <span className={styles.header__logoBox__title}>PhotoSplash</span>
      </div>
      <div className={styles.header__profileBox}>
        <button className={styles.header__profileBox__button}>사진제출</button>
        <button
            className={styles.header__profileBox__button}
            onClick={() => moveToPage("bookmark")}
        >
          북마크
        </button>
        <button className={styles.header__profileBox__button} onClick={openLoginModal}>로그인</button>
        <button className={styles.header__profileBox__button} onClick={openSignupModal}>회원가입</button>
        <span className={styles.header__profileBox__userName}>
          9Diin | 9Diin@Youtube.com
        </span>
      </div>


      {/* 로그인 모달 */}
      <Modal open={isLoginOpen} onClose={closeModal}>
        <Login />
      </Modal>

      {/* 회원가입 모달 */}
      <Modal open={isSignupOpen} onClose={closeModal}>
        <Signup />
      </Modal>
    </header>
  );
}

export default CommonHeader;
