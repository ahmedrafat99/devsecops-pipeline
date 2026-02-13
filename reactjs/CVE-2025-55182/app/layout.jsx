export const metadata = {
  title: "Vulnerable RSC PoC"
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
