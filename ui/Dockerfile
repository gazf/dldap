FROM denoland/deno:2.3.3

WORKDIR /app

# 依存関係のキャッシュ
COPY deno.json deno.lock ./
RUN deno install --frozen

# ソースをコピーして Vite ビルド
COPY . .
RUN deno task build

EXPOSE 3000

ENV PORT=3000

CMD ["deno", "serve", "-A", "--port=3000", "_fresh/server.js"]
