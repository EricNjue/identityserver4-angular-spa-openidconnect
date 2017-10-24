import { Component, OnInit } from '@angular/core';
import {Http, Headers, RequestOptions} from '@angular/http';
import {AuthService} from '../services/auth.service';

@Component({
  selector: 'app-call-api',
  templateUrl: './call-api.component.html',
  styleUrls: ['./call-api.component.css']
})
export class CallApiComponent implements OnInit {

  response: string[] = [];
  remote_names_url = 'https://localhost:44398/api/values';
  constructor(private http: Http, private authService: AuthService) { }

  ngOnInit() {
    const header = new Headers({'Authorization': this.authService.getAuthorizationHeaderValue()});
    const options = new RequestOptions({headers: header});

    this.http.get(this.remote_names_url, options)
      .subscribe(response => {
        console.log(response);
        this.response = response.json();
      });
  }

}
