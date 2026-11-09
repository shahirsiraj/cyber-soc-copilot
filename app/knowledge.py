from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KnowledgeChunk:
    chunk_id: str
    source: str
    category: str
    text: str

def chunk_markdown_file(
    path: Path,
    max_characters: int = 900,
) -> list[KnowledgeChunk]:

    text = path.read_text(
        encoding="utf-8"
    )

    paragraphs = [
        paragraph.strip()
        for paragraph in text.split("\n\n")
        if paragraph.strip()
    ]

    chunks: list[KnowledgeChunk] = []

    current_paragraphs: list[str] = []

    current_length = 0

    chunk_number = 0

    for paragraph in paragraphs:
    
        separator_length = (
            2
            if current_paragraphs
            else 0
        )
    
        additional_length = (
            len(paragraph)
            + separator_length
        )
    
        if (
            current_paragraphs
            and current_length
            + additional_length
            > max_characters
        ):
    
            chunk_text = "\n\n".join(
                current_paragraphs
            )
    
            chunks.append(
                KnowledgeChunk(
                    chunk_id=(
                        f"{path.stem}-"
                        f"{chunk_number:03d}"
                    ),
                    source=path.name,
                    category=path.parent.name,
                    text=chunk_text,
                )
            )
    
            chunk_number += 1
    
            current_paragraphs = []
    
            current_length = 0
    
        current_paragraphs.append(
            paragraph
        )
    
        current_length += (
            len(paragraph)
            + (
                2
                if len(
                    current_paragraphs
                ) > 1
                else 0
            )
        )

    if current_paragraphs:

        chunk_text = "\n\n".join(
            current_paragraphs
        )

        chunks.append(
            KnowledgeChunk(
                chunk_id=(
                    f"{path.stem}-"
                    f"{chunk_number:03d}"
                ),
                source=path.name,
                category=path.parent.name,
                text=chunk_text,
            )
        )

    return chunks

def load_knowledge_chunks(
    knowledge_directory: Path,
) -> list[KnowledgeChunk]:

    chunks: list[KnowledgeChunk] = []

    markdown_files = sorted(
        knowledge_directory.rglob(
            "*.md"
        )
    )

    for path in markdown_files:

        chunks.extend(
            chunk_markdown_file(
                path
            )
        )

    return chunks