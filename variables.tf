variable "aws_region" {
  type    = string
  default = "ap-south-1"
}

variable "alert_email" {
  description = "Email address to receive IAM audit reports"
  type        = string
}
variable "max_key_age_days" {
  description = "Maximum permitted IAM access key age"
  type        = number
  default     = 90
}
