import { useMemo } from 'react';
import QRCode from 'qrcode';

interface QrCodeSvgProps {
  value: string;
  size?: number;
  label?: string;
}

export function QrCodeSvg({
  value,
  size = 192,
  label = 'TOTP 등록용 QR 코드',
}: QrCodeSvgProps) {
  const { totalSize, pathData } = useMemo(() => {
    if (!value) {
      return { totalSize: 21, pathData: '' };
    }
    const qr = QRCode.create(value, { errorCorrectionLevel: 'M' });
    const count = qr.modules.size;
    const margin = 2;
    const parts: string[] = [];

    for (let row = 0; row < count; row += 1) {
      for (let col = 0; col < count; col += 1) {
        if (qr.modules.get(row, col)) {
          parts.push(`M${col + margin} ${row + margin}h1v1h-1z`);
        }
      }
    }
    return {
      totalSize: count + margin * 2,
      pathData: parts.join(''),
    };
  }, [value]);

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${totalSize} ${totalSize}`}
      className="rounded-lg border border-slate-700 bg-white p-1 shadow-md"
      role="img"
      aria-label={label}
      shapeRendering="crispEdges"
    >
      <rect x={0} y={0} width={totalSize} height={totalSize} fill="#ffffff" />
      {pathData && <path d={pathData} fill="#090f1d" />}
    </svg>
  );
}
