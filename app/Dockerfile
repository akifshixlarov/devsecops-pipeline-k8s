# syntax=docker/dockerfile:1.7
#
# ─────────────────────────────────────────────────────────────────────────
# İstifadə olunan versiyalar (izlənilə bilən, dəyişəndə bu fayl yenilənməlidir):
#   Builder base : node:20.17.0-alpine3.20  (Node.js 20 LTS, musl libc)
#   Runtime base : gcr.io/distroless/nodejs20-debian12:nonroot (Node.js 20, glibc, UID 65532)
# Qeyd: dependency-lərimizin heç biri (express, helmet, cors, express-rate-limit,
# pino, pino-http) native/compiled addon istifadə etmir — ona görə musl (Alpine)
# ilə build edilmiş node_modules-un glibc (Debian) runtime-a köçürülməsi təhlükəsizdir.
# Native addon əlavə edilərsə, builder-i node:20-slim (Debian) ilə əvəz edin ki,
# libc uyğunsuzluğu yaranmasın.
# ─────────────────────────────────────────────────────────────────────────

#############################################
# Stage 1 — dependencies (yalnız build üçün) #
#############################################
FROM node:20.17.0-alpine3.20 AS deps

WORKDIR /app

# Əvvəlcə yalnız manifest fayllarını kopyalamaq layer cache-dən maksimum
# faydalanmaq üçündür: kod dəyişəndə (amma dependency-lər dəyişməyəndə)
# `npm ci` addımı yenidən icra olunmur.
COPY package.json package-lock.json* ./

# `npm ci`: package-lock.json-a 1:1 uyğun, deterministik quraşdırma.
# `--omit=dev`: yalnız production dependency-lər — devDependencies (jest,
# eslint, supertest) runtime image-ə heç vaxt daxil olmur (attack surface azalır).
# Lock file yoxdursa və ya uyğun deyilsə bu addım FAIL olur — bu, qəsdəndir
# (immutable, reproducible build tələbi).
RUN npm ci --omit=dev --no-audit --no-fund

#############################################
# Stage 2 — runtime (istehsalata gedən image) #
#############################################
# Niyə distroless?
#   - Shell yoxdur (/bin/sh belə yoxdur) → RCE halında belə interaktiv
#     shell əldə etmək mümkün deyil.
#   - Package manager yoxdur → konteyner daxilində əlavə alət quraşdırmaq
#     mümkün deyil (immutable runtime).
#   - Yalnız Node.js runtime + minimal Debian əsası — OS-səviyyəli CVE
#     sayı standart `node:20` image-ə nisbətən dramatik azdır (bax Gate 6 —
#     Trivy image scan, bu fərq görüləcək).
#   - ":nonroot" tag-i artıq UID/GID 65532 ("nonroot") istifadəçisi ilə
#     işləyir — əlavə `USER` yaratmağa ehtiyac yoxdur.
FROM gcr.io/distroless/nodejs20-debian12:nonroot AS runtime

WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000

# --chown=nonroot:nonroot: köçürülən fayllar runtime istifadəçisinə məxsus
# olur (kök tərəfindən yazılan, sonra qeyri-səlahiyyətli oxunan fayl modelindən qaçırıq).
COPY --from=deps --chown=nonroot:nonroot /app/node_modules ./node_modules
COPY --chown=nonroot:nonroot package.json ./
COPY --chown=nonroot:nonroot src ./src
COPY --chown=nonroot:nonroot healthcheck.js ./

# Distroless image-in "nonroot" tag-i default istifadəçini artıq nonroot
# təyin edir; bu sətir niyyəti açıq şəkildə sənədləşdirir və gələcəkdə
# kimsə base image-i dəyişsə belə (root variant), buildi qırmır.
USER nonroot

EXPOSE 3000

# Distroless-da shell olmadığı üçün HEALTHCHECK exec-form (JSON array) istifadə
# edir — bu, /bin/sh -c çağırmadan birbaşa node binary-ni işə salır (base image
# ENTRYPOINT-i onsuz da "node"-dur, ona görə PATH-də mövcuddur).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "/app/healthcheck.js"]

# Base image-in ENTRYPOINT-i artıq ["node"]-dur (distroless nodejs sənədləşməsinə
# əsasən) — biz yalnız işə salınacaq faylı CMD kimi göstəririk.
CMD ["src/server.js"]
