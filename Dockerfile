# 프리헷 물류 배치도 - 파이썬 기본 라이브러리만 사용 (추가 설치 없음)
FROM python:3.12-slim
WORKDIR /app
COPY index.html server.py layout.json ./
ENV PORT=8080 \
    FRIHET_DATA_DIR=/app/data \
    PYTHONUNBUFFERED=1
# 재고 데이터 폴더: 재배포해도 남도록 영구 볼륨 연결 권장
VOLUME ["/app/data"]
EXPOSE 8080
CMD ["python", "server.py"]
