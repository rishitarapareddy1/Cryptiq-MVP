"use client";

import { useCallback, useRef, useState } from "react";

type ToastType = "" | "success" | "error";

export function useToast() {
  const [msg, setMsg] = useState("");
  const [type, setType] = useState<ToastType>("");
  const [show, setShow] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const toast = useCallback((message: string, t: ToastType = "") => {
    setMsg(message);
    setType(t);
    setShow(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setShow(false), 3600);
  }, []);

  const Toast = () => (
    <div id="toast" className={`${show ? "show " : ""}${type}`}>
      {msg}
    </div>
  );

  return { toast, Toast };
}