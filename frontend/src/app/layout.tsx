import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Providers from "@/components/providers";
import Sidebar from "@/components/sidebar";

const inter = Inter({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  title: "YAROX — AI Security Command Center",
  description: "AI agents autonomously investigating cybersecurity incidents in real time. Watch reasoning, handoffs, and evidence collection as they happen.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${inter.className} antialiased min-h-screen flex`}>
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
