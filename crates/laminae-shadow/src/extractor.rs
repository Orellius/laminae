/// A code block extracted from markdown-formatted LLM output.
#[derive(Debug, Clone)]
pub struct ExtractedBlock {
    /// Language hint from the fence (e.g., "python", "bash", "rust").
    pub language: Option<String>,
    /// The code content without fence markers.
    pub content: String,
    /// Character offset in the original text where this block starts.
    pub char_offset: usize,
}

/// Stateless code block extractor — parses markdown fenced code blocks.
#[derive(Debug, Clone)]
pub struct CodeBlockExtractor;

impl CodeBlockExtractor {
    pub fn new() -> Self {
        Self
    }

    /// Extract all fenced code blocks from the given text.
    pub fn extract(&self, text: &str) -> Vec<ExtractedBlock> {
        let mut blocks = Vec::new();
        let mut chars = text.char_indices().peekable();
        let mut in_block = false;
        let mut block_lang: Option<String> = None;
        let mut block_start: usize = 0;
        let mut block_content_start: usize = 0;

        while let Some(&(i, c)) = chars.peek() {
            if !in_block {
                if c == '`' && self.is_line_start(text, i) {
                    if let Some(fence_end) = self.try_parse_fence(text, i) {
                        let fence_line = &text[i..fence_end];
                        let backtick_end = fence_line
                            .find(|c: char| c != '`')
                            .unwrap_or(fence_line.len());

                        if backtick_end >= 3 {
                            let lang_str = fence_line[backtick_end..].trim();
                            block_lang = if lang_str.is_empty() {
                                None
                            } else {
                                Some(
                                    lang_str
                                        .split_whitespace()
                                        .next()
                                        .unwrap_or("")
                                        .to_lowercase(),
                                )
                            };
                            block_start = i;
                            block_content_start = text[fence_end..]
                                .find('\n')
                                .map(|nl| fence_end + nl + 1)
                                .unwrap_or(fence_end);
                            in_block = true;

                            while let Some(&(j, _)) = chars.peek() {
                                if j >= block_content_start {
                                    break;
                                }
                                chars.next();
                            }
                            continue;
                        }
                    }
                }
            } else if c == '`' && self.is_line_start(text, i) {
                let remaining = &text[i..];
                let backtick_count = remaining.chars().take_while(|&c| c == '`').count();
                if backtick_count >= 3 {
                    let content = &text[block_content_start..i];
                    let content = content.strip_suffix('\n').unwrap_or(content);

                    if !content.trim().is_empty() {
                        blocks.push(ExtractedBlock {
                            language: block_lang.take(),
                            content: content.to_string(),
                            char_offset: block_start,
                        });
                    }

                    in_block = false;
                    block_lang = None;

                    for _ in 0..backtick_count {
                        chars.next();
                    }
                    while let Some(&(_, ch)) = chars.peek() {
                        chars.next();
                        if ch == '\n' {
                            break;
                        }
                    }
                    continue;
                }
            }
            chars.next();
        }

        blocks
    }

    fn is_line_start(&self, text: &str, i: usize) -> bool {
        i == 0 || text.as_bytes().get(i.wrapping_sub(1)) == Some(&b'\n')
    }

    fn try_parse_fence(&self, text: &str, i: usize) -> Option<usize> {
        let remaining = &text[i..];
        let backtick_count = remaining.chars().take_while(|&c| c == '`').count();
        if backtick_count >= 3 {
            let line_end = remaining.find('\n').unwrap_or(remaining.len());
            Some(i + line_end)
        } else {
            None
        }
    }
}

impl Default for CodeBlockExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_single_block() {
        let text = "Here's code:\n```python\nprint('hello')\n```\nDone.";
        let blocks = CodeBlockExtractor::new().extract(text);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].language.as_deref(), Some("python"));
        assert!(blocks[0].content.contains("print('hello')"));
    }

    #[test]
    fn test_extract_multiple_blocks() {
        let text = "```bash\nls -la\n```\nThen:\n```rust\nfn main() {}\n```\n";
        let blocks = CodeBlockExtractor::new().extract(text);
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn test_no_language() {
        let text = "```\nsome code\n```";
        let blocks = CodeBlockExtractor::new().extract(text);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].language.is_none());
    }

    #[test]
    fn test_unclosed_fence() {
        let blocks = CodeBlockExtractor::new().extract("```python\nnever closes");
        assert!(blocks.is_empty());
    }

    #[test]
    fn test_inline_backticks_ignored() {
        let blocks = CodeBlockExtractor::new().extract("Use `eval()` carefully.");
        assert!(blocks.is_empty());
    }
}
