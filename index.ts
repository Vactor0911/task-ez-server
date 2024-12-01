import express from "express";
import cors from "cors";
const PORT = 3001; // 서버가 실행될 포트 번호

const app = express();
app.use(cors());

// 기본 라우트 설정
app.get("/", (req, res) => {
  res.send("Task Ez Web Server!");
});

// 서버 시작
app.listen(PORT, "0.0.0.0", () => {
  console.log(`서버가 ${PORT}번 포트에서 실행 중입니다.`);
});
