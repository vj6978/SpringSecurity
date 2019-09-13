package com.example.demo.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Hello 
{
	@GetMapping("/hello")
	public String sayHi()
	{
		return "Hi There!";
	}
}
