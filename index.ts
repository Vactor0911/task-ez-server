import express, { Request, Response } from "express";
import cors from "cors";
import MariaDB from 'mariadb';
import bcrypt from 'bcrypt'; // 비밀번호 암호화 최신버전 express 에서 가지고 있다함
import dotenv from 'dotenv'; // 환경 변수 사용한 민감한 정보 관리


// .env 파일 로드
dotenv.config();

const PORT = 3005; // 서버가 실행될 포트 번호

const app = express();
app.use(cors());
app.use(express.json());  // JSON 요청을 처리하기 위한 미들웨어

// MariaDB 연결 (createPool 사용)
const db = MariaDB.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: 10,
});

console.log(process.env.DB_HOST, process.env.DB_PORT, process.env.DB_USERNAME, process.env.DB_PASSWORD, process.env.DB_NAME);

// MariaDB 연결 확인
db.getConnection()
    .then(conn => {
        console.log("task-ez 데이터베이스가 성공적으로 연결되었습니다");
        conn.release();
    })
    .catch(err => {
        console.error("데이터베이스 연결에 실패하였습니다.", err.message);
    });


// 기본 라우트 설정
app.get("/", (req, res) => {
  res.send("Task Ez Web Server!");
});

// 서버 시작
app.listen(PORT, "0.0.0.0", () => {
  console.log(`서버가 ${PORT}번 포트에서 실행 중입니다.`);
});


// *** 사용자 로그인 API 시작
app.post('/api/login', (req: Request, res: Response) => {
  const { email, password } = req.body;

  console.log("로그인 요청 받은 데이터:", { email, password });

  // Step 1: 이메일로 사용자 조회
  db.query('SELECT * FROM user WHERE email = ?', [email])
    .then((rows: any) => {
      console.log("사용자 조회 결과:", rows);

      if (rows.length === 0) {
        // 사용자가 없는 경우
        console.log("사용자를 찾을 수 없습니다:", email);
        return res.status(401).json({
          success: false,
          message: '사용자를 찾을 수 없습니다. 회원가입 후 이용해주세요.',
        });
      }

      const user = rows[0];

      // Step 3: 암호화된 비밀번호 비교
      return bcrypt.compare(password, user.password).then((isPasswordMatch) => {
        if (!isPasswordMatch) {
          console.log("비밀번호가 일치하지 않습니다");
          return res.status(401).json({
            success: false,
            message: '비밀번호가 일치하지 않습니다',
          });
        }

        // Step 4: 로그인 성공 처리
        const nickname = user.name; // DB의 name 필드를 닉네임으로 사용
        console.log(`[${email}] ${nickname}님 로그인 성공`);
        res.json({
          success: true,
          message: '로그인 성공',
          nickname: nickname, // 닉네임 반환
        });
      });
    })
    .catch((err) => {
      // 에러 처리
      console.error("서버 오류 발생:", err);
      res.status(500).json({
        success: false,
        message: '서버 오류 발생',
        error: err.message,
      });
    });
}); // 사용자 로그인 API 끝


// *** 로그아웃 API 수정 ***
app.post('/api/logout', async (req: Request, res: Response) => {
  const { email } = req.body;

  console.log("로그아웃 요청 받은 데이터:", { email });

  try {
    // Step 1: 사용자 조회
    const rows = await db.query("SELECT * FROM user WHERE email = ?", [email]);

    if (rows.length === 0) {
      // 사용자 정보를 찾지 못한 경우
      return res.status(404).json({ success: false, message: "사용자를 찾을 수 없습니다." });
    }

    console.log(`[${email}] 님의 로그아웃이 성공적으로 완료되었습니다.`);

    // Step 4: 성공 응답 반환
    res.status(200).json({ success: true, message: "로그아웃이 성공적으로 완료되었습니다." });
  } catch (err) {
    // Step 5: 에러 처리
    console.error("로그아웃 처리 중 오류 발생:", err);
    res.status(500).json({ success: false, message: "로그아웃 처리 중 오류가 발생했습니다." });
  }
}); // *** 로그아웃 API 끝 ***



// *** 사용자 회원가입 API 시작
app.post('/api/register', (req: Request, res: Response) => {
  const { email, password, name } = req.body as { email: string; password: string; name: string; };
  console.log("받은 데이터:", { email, password, name });

  // Step 1: 이메일 중복 확인
  db.query('SELECT * FROM user WHERE email = ?', [email])
    .then((rows_email: any) => {
      if (rows_email.length > 0) {
        console.log("이메일이 이미 존재합니다:", email);
        return res.status(400).json({ success: false, message: '이메일이 이미 존재합니다' });
      }

      // Step 2: 비밀번호 암호화
      return bcrypt.hash(password, 10);
    })
    .then((hashedPassword: string) => {
      console.log("Hashed password:", hashedPassword);

      // Step 3: 사용자 저장
      return db.query(
        'INSERT INTO user (email, password, plain_password, name) VALUES (?, ?, ?, ?)',
        [email, hashedPassword, password, name]
      );
    })
    .then((result: any) => {
      console.log("사용자 삽입 결과:", result);
      res.status(201).json({ success: true, message: '사용자가 성공적으로 등록되었습니다' });
    })
    .catch((err: any) => {
      // Step 4: 에러 처리
      console.error("서버 오류 발생:", err);
      res.status(500).json({ success: false, message: '서버 오류 발생', error: err.message });
    });
}); // *** 사용자 회원가입 API 끝
