"""명령줄 진입점: `avissguard` 또는 `python -m avissguard`."""

from __future__ import annotations

import argparse
import sys
import logging
import webbrowser


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        prog="avissguard",
        description="시험장 BLE 부정행위 기기(초소형 카메라·이어폰·스마트안경) 탐지 대시보드",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--simulate", action="store_true", help="블루투스 없이 가상 기기 시나리오로 실행 (데모)")
    mode.add_argument("--no-scan", action="store_true", help="스캐너 없이 서버만 실행")
    p.add_argument("--host", default="127.0.0.1", help="바인딩 주소 (기본 127.0.0.1, 외부 공개 시 0.0.0.0)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--db", default="avissguard.db", help="SQLite 기록 파일 경로")
    p.add_argument("--signatures", default=None, help="사용자 시그니처 JSON 경로 (기본: 내장 DB)")
    p.add_argument("--ttl", type=float, default=30.0, help="이 시간(초) 동안 신호가 없으면 화면에서 제외")
    p.add_argument("--near-rssi", type=int, default=-60, help="이 값 이상이면 '매우 가까움'으로 가점")
    p.add_argument("--min-rssi", type=int, default=-100, help="이보다 약한 신호는 무시 (먼 교실 기기 걸러내기)")
    p.add_argument("--adapter", default=None, help="Linux BlueZ 어댑터 이름 (예: hci1)")
    p.add_argument("--token", default=None, help="대시보드 접속 토큰 (기본: 실행할 때마다 임의 생성)")
    p.add_argument("--open", action="store_true", help="실행 후 브라우저로 대시보드 열기")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    import uvicorn

    from .server import create_app

    scanner = "simulate" if args.simulate else ("none" if args.no_scan else "ble")
    app = create_app(
        scanner=scanner,
        db_path=args.db,
        signatures_path=args.signatures,
        ttl=args.ttl,
        near_rssi=args.near_rssi,
        min_rssi=args.min_rssi,
        adapter=args.adapter,
        token=args.token,
    )
    base = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
    url = f"{base}/?token={app.state.token}"
    print(f"\n  AvissGuard 대시보드: {url}\n  (모드: {scanner} · 토큰이 없는 접속은 거부됩니다. 이 URL은 공유하지 마세요)\n", flush=True)
    if args.host in ("0.0.0.0", "::"):
        print("  [주의] 같은 네트워크의 누구나 접속을 시도할 수 있습니다. 응시자와 같은 Wi-Fi라면 --host 127.0.0.1을 쓰세요.\n")
    if scanner == "ble" and sys.platform == "darwin":
        print(
            "  [macOS] 블루투스 권한이 없으면 'Abort trap: 6'(종료 코드 134)로 바로 꺼집니다.\n"
            "  시스템 설정 → 개인정보 보호 및 보안 → 블루투스에서 이 터미널 앱을 허용하세요.\n"
        )
    if args.open:
        webbrowser.open(url)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
