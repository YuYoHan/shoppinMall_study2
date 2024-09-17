import { useEffect, useState } from "react";
import CommonHeader from "@/components/common/header/CommonHeader";
import Card from "./components/Card";
// CSS
import styles from "./styles/index.module.scss";
import { CardDTO } from "../index/types/card";

function Index() {
  // 컴포넌트 이름을 대문자로 수정
  const [data, setData] = useState<CardDTO[]>([]); // useState 타입 추가

  const getData = () => {
    const getLocalStorage = JSON.parse(
      localStorage.getItem("bookmark") || "[]"
    );

    if (getLocalStorage && getLocalStorage !== null) setData(getLocalStorage);
    else setData([]);
  };

  useEffect(() => {
    getData();
  }, []);

  return (
    <div className={styles.page}>
      {/* 공통 헤더 UI 부분 */}
      <CommonHeader />
      <main className={styles.page__contents}>
        {data.map((item: CardDTO) => {
          return <Card data={item} key={item.id} />;
        })}
      </main>
    </div>
  );
}

export default Index; // 컴포넌트 이름을 대문자로 수정
