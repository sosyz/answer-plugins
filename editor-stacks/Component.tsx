/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { FC, useCallback, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import { StacksEditor } from "@stackoverflow/stacks-editor";

import "@stackoverflow/stacks";
import "@stackoverflow/stacks/dist/css/stacks.css";

import "@stackoverflow/stacks-editor/dist/styles.css";

export interface EditorProps {
  value: string;
  onChange?: (value: string) => void;
  onFocus?: () => void;
  onBlur?: () => void;
  placeholder?: string;
  autoFocus?: boolean;
  imageUploadHandler?: (file: File | string) => Promise<string>;
  uploadConfig?: {
    maxImageSizeMiB?: number;
    allowedExtensions?: string[];
  };
}

const Component: FC<EditorProps> = ({
  value,
  onChange,
  onFocus,
  onBlur,
  placeholder = "",
  autoFocus = false,
  imageUploadHandler,
  uploadConfig,
}) => {
  const { t } = useTranslation("plugin", {
    keyPrefix: "editor_stacks.frontend",
  });
  const containerRef = useRef<HTMLDivElement>(null);
  const editorInstanceRef = useRef<StacksEditor | null>(null);
  const isInitializedRef = useRef(false);

  // Version compatibility temporarily disabled

  const syncTheme = useCallback(() => {
    if (!containerRef.current) return;

    containerRef.current.parentElement?.classList.remove(
      "theme-light",
      "theme-dark",
      "theme-system",
    );
    const themeAttr =
      document.documentElement.getAttribute("data-bs-theme") ||
      document.body.getAttribute("data-bs-theme");

    if (themeAttr) {
      containerRef.current.parentElement?.classList.add(`theme-system`);
    }
  }, []);

  useEffect(() => {
    syncTheme();
  }, [syncTheme]);

  useEffect(() => {
    const observer = new MutationObserver(() => {
      syncTheme();
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-bs-theme", "class"],
    });
    observer.observe(document.body, {
      attributes: true,
      attributeFilter: ["data-bs-theme", "class"],
    });
    return () => observer.disconnect();
  }, [syncTheme]);

  useEffect(() => {
    if (!containerRef.current || isInitializedRef.current) {
      return;
    }

    const container = document.createElement("div");
    container.className = "stacks-editor-container";
    container.style.minHeight = "320px";
    containerRef.current.appendChild(container);

    let editorInstance: StacksEditor | null = null;

    try {
      editorInstance = new StacksEditor(container, value || "", {
        placeholderText: placeholder || t("placeholder", ""),
        parserFeatures: {
          tables: true,
          html: false,
        },
        imageUpload: imageUploadHandler
          ? {
              handler: imageUploadHandler,
              sizeLimitMib: uploadConfig?.maxImageSizeMiB,
              acceptedFileTypes: uploadConfig?.allowedExtensions,
            }
          : undefined,
      });

      editorInstanceRef.current = editorInstance;
      isInitializedRef.current = true;

      const editor = editorInstance;

      const originalDispatch = editor.editorView.props.dispatchTransaction;
      editor.editorView.setProps({
        dispatchTransaction: (tr) => {
          if (originalDispatch) {
            originalDispatch.call(editor.editorView, tr);
          } else {
            const newState = editor.editorView.state.apply(tr);
            editor.editorView.updateState(newState);
          }

          if (tr.docChanged && onChange) {
            const newContent = editor.content;
            onChange(newContent);
          }
        },
      });

      const editorElement = editor.dom as HTMLElement;
      if (editorElement) {
        const handleFocus = () => onFocus?.();
        const handleBlur = () => onBlur?.();
        editorElement.addEventListener("focus", handleFocus, true);
        editorElement.addEventListener("blur", handleBlur, true);
      }

      if (autoFocus) {
        setTimeout(() => {
          if (editor) {
            editor.focus();
          }
        }, 100);
      }

      return () => {
        if (editorInstance) {
          try {
            editorInstance.destroy();
          } catch (e) {
            console.error("Error destroying editor:", e);
          }
        }

        editorInstanceRef.current = null;
        isInitializedRef.current = false;

        try {
          container.remove();
        } catch {}
      };
    } catch (error) {
      console.error("Failed to initialize Stacks Editor:", error);
      isInitializedRef.current = false;
    }
  }, []);

  useEffect(() => {
    const editor = editorInstanceRef.current;
    if (!editor || !isInitializedRef.current) {
      return;
    }

    try {
      if (editor.content !== value) {
        editor.content = value;
      }
    } catch (error) {
      console.error("Error syncing editor content:", error);
    }
  }, [value]);

  return (
    <div className="editor-stacks-wrapper editor-stacks-scope">
      <div ref={containerRef} style={{ minHeight: 320 }} />
    </div>
  );
};

export default Component;
