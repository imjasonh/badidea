terraform {
  required_providers {
    ko = { source = "ko-build/ko" }
  }
}

variable "project" { type = string }
variable "region" { type = string }

provider "google" {
  project = var.project
  region  = var.region
}

provider "ko" { repo = "gcr.io/${var.project}/badidea" }

module "networking" {
  source = "chainguard-dev/common/infra//modules/networking"

  name       = "badidea"
  project_id = var.project
  regions    = [var.region]
}

resource "google_service_account" "sa" {
  account_id = "badidea"
  project    = var.project
}

// Create a basic GKE Autopilot cluster.
resource "google_container_cluster" "cluster" {
  name             = "badidea"
  enable_autopilot = true
  release_channel { channel = "RAPID" }
}

// Let the SA manage the cluster.
resource "google_project_iam_member" "member" {
  project = var.project
  role    = "roles/container.admin"
  member  = "serviceAccount:${google_service_account.sa.email}"
}

module "service" {
  depends_on = [google_container_cluster.cluster]

  source  = "chainguard-dev/common/infra//modules/regional-go-service"
  version = "0.5.20"

  ingress = "INGRESS_TRAFFIC_ALL" // TODO: GCLB
  egress  = "PRIVATE_RANGES_ONLY"

  execution_environment = "EXECUTION_ENVIRONMENT_GEN2"

  name            = "badidea"
  project_id      = var.project
  regions         = module.networking.regional-networks
  service_account = google_service_account.sa.email
  containers = {
    "badidea" = {
      source = {
        importpath  = "./"
        working_dir = path.module
      }
      ports = [{ container_port = 8080 }]
      env = [{
        name  = "CLUSTER_NAME"
        value = google_container_cluster.cluster.name
      }]
    }

  }
  notification_channels = []
}

data "google_cloud_run_v2_service" "service" {
  depends_on = [module.service]
  project    = var.project
  location   = var.region
  name       = module.service.names[var.region]
}

output "url" { value = data.google_cloud_run_v2_service.service.uri }
