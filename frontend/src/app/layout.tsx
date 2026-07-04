import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Providers from "@/components/providers";
import Sidebar from "@/components/sidebar";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "YAROX - Autonomous Security Investigation",
  description: "Enterprise-grade AI platform that autonomously investigates cybersecurity incidents.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-zinc-950 text-zinc-50 antialiased min-h-screen flex`}>
        <Providers>
          <Sidebar />
          <main className="flex-1 flex flex-col min-h-screen overflow-hidden">
            {children}
          </main>
        </Providers>
      </body>
    </html>
  );
}
