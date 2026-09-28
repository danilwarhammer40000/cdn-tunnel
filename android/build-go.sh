#!/usr/bin/env bash
# Собирает Go-часть, которую упаковывает APK:
#   jniLibs/arm64-v8a/libtun.so      — клиент туннеля (main.go -client), CGO обязателен для DNS
#   assets/server/cdn-tunnel-amd64   — серверная часть для VPS (её заливает автодеплой)
#   assets/server/cdn-tunnel-arm64
#
# Вызывается из Gradle перед сборкой APK: иначе легко забыть пересобрать бинари
# после правок main.go и увезти на сервер устаревшую сборку.
#
# Кросс-платформенно: NDK на Linux/macOS/Windows кладёт toolchain в папку с
# разным именем (linux-x86_64 / darwin-x86_64 / windows-x86_64), а на Windows
# сам компилятор — обёртка .cmd, а не голый бинарь.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
target="$root/android/app/src/main/jniLibs/arm64-v8a/libtun.so"

if ! command -v go >/dev/null 2>&1; then
  echo "build-go: go не найден — оставляю уже собранные бинари как есть" >&2
  exit 0
fi

sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$sdk" ] && [ -f "$here/local.properties" ]; then
  # Android Studio при синхронизации пишет android/local.properties с sdk.dir —
  # резервный источник, если переменные окружения не долетели до задачи Gradle.
  # В файле путь экранирован по правилам .properties: C\:\\Users\\... -> C:/Users/...
  sdk="$(sed -n 's/^sdk\.dir=//p' "$here/local.properties" | tail -1 | tr -d '\r' | sed 's/\\\\/\//g; s/\\:/:/g')"
fi
sdk="${sdk:-$HOME/Android/Sdk}"
sdk="${sdk//\\//}"   # обратные слэши Windows -> прямые, иначе не сработает glob ниже

cc=""
for host in linux-x86_64 darwin-x86_64 windows-x86_64; do
  for d in "$sdk"/ndk/*/toolchains/llvm/prebuilt/"$host"/bin; do
    for exe in aarch64-linux-android24-clang aarch64-linux-android24-clang.cmd; do
      if [ -x "$d/$exe" ]; then
        cc="$d/$exe"
        break 3
      fi
    done
  done
done

if [ -n "$cc" ]; then
  echo "build-go: libtun.so (android/arm64), CC=$cc"
  ( cd "$root" && CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC="$cc" \
      go build -trimpath -ldflags "-s -w" \
      -o "$target" . )
elif [ -f "$target" ]; then
  echo "build-go: NDK (toolchain aarch64-linux-android24-clang) не найден — использую уже собранный libtun.so, он может быть устаревшим!" >&2
  echo "build-go: искал под sdk.dir=$sdk — проверьте, что NDK установлен через Android Studio SDK Manager (SDK Tools → NDK Side by side)" >&2
else
  echo "build-go: NDK не найден, а libtun.so ещё никогда не собирался — собрать APK нечем." >&2
  echo "build-go: искал под sdk.dir=$sdk — установите NDK через Android Studio (Settings → Android SDK → SDK Tools → NDK Side by side)" >&2
  echo "build-go: если NDK установлен в нестандартное место, задайте переменную окружения ANDROID_HOME или ANDROID_SDK_ROOT." >&2
  exit 1
fi

echo "build-go: серверные бинари (linux amd64/arm64)"
( cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" \
    -o android/app/src/main/assets/server/cdn-tunnel-amd64 . )
( cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" \
    -o android/app/src/main/assets/server/cdn-tunnel-arm64 . )
echo "build-go: готово"
