import requests
import os

SERVER_URL = "http://127.0.0.1:8000/predict"

AUDIO_FOLDER = "./audio"

supported_formats = (
    ".wav",
    ".mp3",
    ".flac",
    ".ogg",
    ".m4a"
)

audios = [
    file for file in os.listdir(AUDIO_FOLDER)
    if file.lower().endswith(supported_formats)
]

if not audios:

    print("No audio files found.")
    exit()

for audio in audios:

    audio_path = os.path.join(
        AUDIO_FOLDER,
        audio
    )

    print(f"\nProcessing: {audio}")

    try:

        with open(audio_path, "rb") as f:

            files = {
                "file": f
            }

            response = requests.post(
                SERVER_URL,
                files=files
            )

        data = response.json()

        print(
            f"Prediction : {data['prediction']}"
        )

        print(
            f"Confidence : {data['confidence']}%"
        )

    except Exception as e:

        print(f"Error processing {audio}")

        print(e)