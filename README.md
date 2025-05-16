# API Gateway

Amazon Cognito 기반 JWT 인증을 지원하는 HTTP API Gateway 서버입니다.

## 환경 변수 설정

서버 실행을 위해 다음 환경 변수를 설정해야 합니다:

### 서버 설정
- `PORT`: API Gateway 서버 포트 (기본값: 3000)
- `TARGET_ENDPOINT`: 프록시 대상이 되는 내부 서버의 엔드포인트 URL (예: http://localhost:8080)

### Amazon Cognito 설정
- `AWS_COGNITO_REGION`: Cognito 리전 (예: ap-northeast-2)
- `AWS_COGNITO_USER_POOL_ID`: Cognito 사용자 풀 ID
- `AWS_COGNITO_CLIENT_ID`: Cognito 앱 클라이언트 ID

## 실행 방법

1. 환경 변수 설정:
```bash
# 서버 설정
export PORT=3000
export TARGET_ENDPOINT=http://localhost:8080

# Cognito 설정
export AWS_COGNITO_REGION=ap-northeast-2
export AWS_COGNITO_USER_POOL_ID=your-user-pool-id
export AWS_COGNITO_CLIENT_ID=your-client-id
```

2. 서버 실행:
```bash
go run cmd/api-gateway/main.go
```

## API 요청 방법

모든 API 요청에는 Cognito에서 발급된 JWT Access 토큰이 필요합니다 (OPTIONS 메서드 제외).

### 헤더 설정
```
Authorization: Bearer <your-cognito-access-token>
```

## 기능

- Amazon Cognito JWT 토큰 기반 인증
  - 토큰 형식 검증
  - 서명 알고리즘 검증
  - 토큰 용도(access) 검증
  - Client ID 검증
  - Issuer 검증
  - 만료 시간 검증
- 모든 HTTP 메서드 지원 (GET, POST, PUT, DELETE, PATCH, OPTIONS)
- CORS 지원
- 요청/응답 로깅
