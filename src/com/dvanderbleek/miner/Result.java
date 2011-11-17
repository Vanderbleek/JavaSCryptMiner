package com.dvanderbleek.miner;
//This is just a class to make parsing JSON with GSON easier.
public class Result {
String midstate;
String data;
String hash1;
String target;

public Result(String midstate, String data, String hash1, String target){
	this.midstate = midstate;
	this.data = data;
	this.hash1 = hash1;
	this.target = target;
}
}
