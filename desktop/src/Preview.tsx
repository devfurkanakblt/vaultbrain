import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export default function MarkdownPreview({ body }: { body: string }) {
  return <article className="markdown-preview"><ReactMarkdown remarkPlugins={[remarkGfm]}>{body}</ReactMarkdown></article>;
}
