import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'ShopShield | Website Risk & Shopping Scam Intelligence System',
  description: 'Evidence-based risk analysis and legitimacy assessment for online shopping websites.'
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
