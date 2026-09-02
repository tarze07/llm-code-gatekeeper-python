// Fixture testowy reguły `no-dangerous-html-unsanitized`.
// Uruchomienie: semgrep --test --config rules/semgrep rules/semgrep/tests
import DOMPurify from 'dompurify';
import sanitizeHtml from 'sanitize-html';
import { marked } from 'marked';

function Preview({ note }: { note: { content: string } }) {
  const html = marked.parse(note.content) as string;

  // ruleid: no-dangerous-html-unsanitized
  const unsafe = <div dangerouslySetInnerHTML={{ __html: html }} />;

  // ok: no-dangerous-html-unsanitized
  const safeDomPurify = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;

  // ok: no-dangerous-html-unsanitized
  const safeSanitizeHtml = <div dangerouslySetInnerHTML={{ __html: sanitizeHtml(html) }} />;

  // ok: no-dangerous-html-unsanitized
  const plainText = <p>{note.content}</p>;

  return (
    <div>
      {unsafe}
      {safeDomPurify}
      {safeSanitizeHtml}
      {plainText}
    </div>
  );
}

export default Preview;
