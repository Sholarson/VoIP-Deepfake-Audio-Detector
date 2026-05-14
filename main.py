from transformers import pipeline
import os

# Load model once
classifier = pipeline(
    "audio-classification",
    model="MelodyMachine/Deepfake-audio-detection-V2"
)

# Audio folder
audio_folder = "./audio"

# Supported formats
supported_formats = (".wav", ".mp3", ".flac", ".ogg", ".m4a")

# Get all audio files
audios = [
    file for file in os.listdir(audio_folder)
    if file.lower().endswith(supported_formats)
]

# Check if folder is empty
if not audios:
    print("No audio files found.")
    exit()

# Process files
for audio in audios:

    audio_path = os.path.join(audio_folder, audio)

    print(f"\nProcessing: {audio}")

    try:
        result = classifier(audio_path)

        top = result[0]

        label = top["label"]
        confidence = top["score"] * 100

        print(f"Prediction : {label}")
        print(f"Confidence : {confidence:.4f}%")

    except Exception as e:
        print(f"Error processing {audio}")
        print(e)